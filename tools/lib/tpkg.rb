# frozen_string_literal: true

# Shared helpers for tebako-packages feedstock tools (spec 13 §9).
# Conventions: tebako-packages/index docs/conventions.md.

require "yaml"
require "json"
require "fileutils"
require "digest"
require "shellwords"
require "open3"

module Tpkg
  ROOT = File.expand_path("../..", __dir__).freeze

  # platform triplet (recipe) => CI runner + vcpkg overlay triplet
  PLATFORM_MAP = {
    "x86_64-linux-gnu"  => { "runner" => "ubuntu-24.04",     "vcpkg_triplet" => "x64-linux-dynamic" },
    "aarch64-linux-gnu" => { "runner" => "ubuntu-24.04-arm", "vcpkg_triplet" => "arm64-linux-dynamic" },
    "aarch64-macos"     => { "runner" => "macos-14",         "vcpkg_triplet" => "arm64-osx-static" },
    "x86_64-macos"      => { "runner" => "macos-13",         "vcpkg_triplet" => "x64-osx-static" }
  }.freeze

  # The glibc family + the program loader stay OUTSIDE the closure: they must
  # match the host kernel/loader (the preload shim provides them). Everything
  # else ldd resolves — including libstdc++/libgcc_s — is packaged.
  CLOSURE_EXCLUDE = %w[
    linux-vdso.so.1 ld-linux-x86-64.so.2 ld-linux-aarch64.so.1 ld-musl-x86_64.so.1
    libc.so.6 libm.so.6 libdl.so.2 libpthread.so.0 librt.so.1
    libresolv.so.2 libutil.so.1 libanl.so.1 libnsl.so.1
  ].freeze
  CLOSURE_EXCLUDE_RE = /\Alibnss_|\Alinux-gate/ .freeze

  # macOS closure exclusions (the libSystem family — the macOS counterpart of
  # the linux glibc rule): anything the OS itself ships under /usr/lib or
  # /System/Library stays outside the closure. That includes libc++.1.dylib /
  # libc++abi.dylib — the libstdc++/libgcc_s equivalents — which on macOS are
  # part of the OS (dyld shared cache, ABI-stable), unlike linux where
  # libstdc++ is a toolchain package and rides in the closure.
  MACOS_SYSTEM_REF = %r{\A/(usr/lib|System/Library)/}.freeze
  # Prefixes a dylib reference may have to count as closure material on macOS.
  # Single supplier (Homebrew), so this is exactly the brew tree(s):
  # /opt/homebrew on arm64, /usr/local (minus /usr/lib) on x86_64.
  MACOS_SUPPLIER_REF = %r{\A/(opt/homebrew|usr/local)/}.freeze

  module_function

  def recipe(path)
    YAML.load_file(path)
  end

  def log(msg)  = $stdout.puts("[tpkg] #{msg}")
  def warn(msg) = $stderr.puts("[tpkg] WARNING: #{msg}")

  def die(msg)
    $stderr.puts("[tpkg] ERROR: #{msg}")
    exit 1
  end

  def sh(*cmd, chdir: nil, env: {}, quiet: false)
    log("$ #{cmd.join(' ')}#{"   (cd #{chdir})" if chdir}") unless quiet
    kw = {}
    kw[:chdir] = chdir if chdir
    system(env, *cmd, **kw) or die("command failed (#{$?.exitstatus}): #{cmd.join(' ')}")
  end

  def capture(*cmd, env: {}, chdir: nil)
    kw = {}
    kw[:chdir] = chdir if chdir
    out, status = Open3.capture2e(env, *cmd, **kw)
    [out, status.success?]
  end

  def sha256(path)
    Digest::SHA256.file(path).hexdigest
  end

  # Fetch url to dest, verifying sha256. One re-download attempt on mismatch;
  # aborts otherwise. Every download in the feedstock goes through here.
  def fetch(url, dest, sha256)
    FileUtils.mkdir_p(File.dirname(dest))
    2.times do |attempt|
      if File.exist?(dest)
        actual = sha256(dest)
        if actual == sha256
          log("cache hit #{File.basename(dest)} sha256=#{actual[0, 16]}…")
          return dest
        end
        warn("cached #{dest} has sha256=#{actual}, expected #{sha256} — refetching")
        FileUtils.rm_f(dest)
      end
      log("fetch #{url}")
      sh("curl", "-fsSL", "--retry", "3", "--no-progress-meter", "-o", dest, url)
      actual = sha256(dest)
      return dest if actual == sha256

      warn("sha256 mismatch after download (attempt #{attempt + 1}): got #{actual}, want #{sha256}")
    end
    die("could not fetch #{url} with expected sha256 #{sha256}")
  end

  # Locate or obtain the image tool: the tfs CLI from the pinned
  # tamatebako/tebako release (recipe image.tfs_cli) — the imager
  # (`tfs mkimage`; limnifs, the default tebako image format) and the
  # smoke's extract reader on every platform. The recipe sha256 pin is
  # the trust anchor AND is cross-checked against the release's own
  # SHA256SUMS (both anchored). $TFS_CLI overrides (a pre-resolved binary
  # wins; the pin dance is skipped).
  def ensure_tfs_cli(recipe, platform: nil)
    if ENV["TFS_CLI"] && File.executable?(ENV["TFS_CLI"])
      log("using $TFS_CLI=#{ENV['TFS_CLI']}")
      return { "tfs" => ENV["TFS_CLI"] }
    end

    spec = recipe.fetch("image").fetch("tfs_cli")
    infix = { "aarch64-macos" => "macos-arm64", "x86_64-macos" => "macos-x86_64",
              "x86_64-linux-gnu" => "linux-gnu-x86_64", "aarch64-linux-gnu" => "linux-gnu-arm64",
              "x86_64-windows-ucrt" => "windows-ucrt64" }[platform]
    die("no tfs CLI asset infix for platform #{platform.inspect}") unless infix
    exe = platform.end_with?("-windows-ucrt") ? ".exe" : ""
    asset = "tfs-#{spec['release'].sub(/\Av/, '')}-#{infix}#{exe}"
    want = spec.fetch("sha256").fetch(asset)
    dir = File.join(cache_dir, "tools", "tebako-#{spec['release']}")
    FileUtils.mkdir_p(dir)
    base = "https://github.com/#{spec.fetch('repo')}/releases/download/#{spec['release']}"
    sums = File.join(dir, "SHA256SUMS")
    unless File.exist?(sums)
      sh("curl", "-fsSL", "--retry", "3", "--no-progress-meter", "-o", sums, "#{base}/SHA256SUMS")
    end
    got = File.readlines(sums).map(&:split).to_h[asset]
    die("pin mismatch for #{asset}: recipe=#{want} release=#{got || 'ABSENT'}") unless got == want
    bin = fetch("#{base}/#{asset}", File.join(dir, asset), want)
    FileUtils.chmod(0o755, bin)
    { "tfs" => bin }
  end


  # Parse `ldd` output into {soname => resolved_path}.
  def ldd_resolve(file, libdirs)
    env = { "LD_LIBRARY_PATH" => libdirs.join(":") }
    out, ok = capture("ldd", file, env: env)
    die("ldd failed on #{file}:\n#{out}") unless ok
    resolved = {}
    out.each_line do |line|
      if line =~ /^\s*(\S+)\s+=>\s+(\/\S+)\s+\(0x[0-9a-f]+\)/ ||
         line =~ /^\s*(\/\S+)\s+\(0x[0-9a-f]+\)/
        name = Regexp.last_match(2) ? Regexp.last_match(1) : File.basename(Regexp.last_match(1))
        path = Regexp.last_match(2) || Regexp.last_match(1)
        resolved[name] = path
      elsif line =~ /(\S+)\s+=>\s+not found/
        resolved[Regexp.last_match(1)] = nil
      end
    end
    resolved
  end

  def elf?(path)
    File.file?(path) && !File.symlink?(path) &&
      File.open(path, "rb") { |f| f.read(4) } == "\x7fELF"
  rescue Errno::EACCES, Errno::ENOENT
    false
  end

  def excluded_lib?(name)
    CLOSURE_EXCLUDE.include?(name) || name.match?(CLOSURE_EXCLUDE_RE)
  end

  # --- macOS (Mach-O) closure ------------------------------------------------

  # Mach-O magics (byte strings): 64/32-bit, both endians, + fat universal.
  MACHO_MAGICS = ["\xcf\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xce", "\xca\xfe\xba\xbe"].map(&:b).freeze

  def macho?(path)
    return false unless File.file?(path) && !File.symlink?(path)

    magic = File.open(path, "rb") { |f| f.read(4) }
    return false if magic.nil? || magic.bytesize < 4

    MACHO_MAGICS.include?(magic)
  rescue Errno::EACCES, Errno::ENOENT
    false
  end

  # All LC_LOAD_DYLIB names + the install name (first entry for dylibs).
  def otool_refs(path)
    out, ok = capture("otool", "-L", path)
    die("otool -L failed on #{path}:\n#{out}") unless ok
    out.each_line.drop(1).filter_map do |line|
      line = line.strip.sub(/\s+\(.*\)\s*$/, "")
      line unless line.empty?
    end
  end

  def otool_rpaths(path)
    out, ok = capture("otool", "-l", path)
    die("otool -l failed on #{path}:\n#{out}") unless ok
    lines = out.each_line.to_a
    rpaths = []
    lines.each_with_index do |line, i|
      rpaths << Regexp.last_match(1) if line.strip == "cmd LC_RPATH" && lines[i + 2].to_s =~ /path (\S+) \(offset/
    end
    rpaths
  end

  # Fixpoint otool walk of the payload tree, closing over every non-system
  # dylib reference into lib/. Rules (documented in docs/build-notes.md):
  #  * /usr/lib + /System/Library refs stay out (the libSystem family).
  #  * Everything else must come from the single supplier (brew tree) and is
  #    copied FLAT into lib/ as <leaf>; a leaf colliding with different
  #    content is an error, not a choice (single supplier ⇒ none expected).
  #  * After copying, every payload Mach-O gets its supplier-absolute refs
  #    rewritten to @rpath/<leaf> and every closure dylib gets
  #    -id @rpath/<leaf> (install_name_tool — the macOS bundling step; the
  #    no-patchelf rule targets RPATH wiring, which stays build-time).
  # Idempotent: re-running wipes the previous run's copies first (their
  # install names were rewritten in place, so they no longer compare equal
  # to the brew originals) — the stamp file records what we copied.
  # Returns {leaf => source realpath}.
  def macos_closure(root, stamp: nil)
    libd = File.join(root, "lib")
    FileUtils.mkdir_p(libd)
    if stamp && File.exist?(stamp)
      File.read(stamp).split("\n").each { |leaf| FileUtils.rm_f(File.join(libd, leaf)) }
    end
    copied = {} # leaf => realpath of the supplier dylib it came from
    system_refs = {}
    payload_leaf = lambda do |leaf|
      File.exist?(File.join(libd, leaf))
    end
    dylibish = ->(f) { f.end_with?(".dylib", ".so") }

    seeds = Dir[File.join(root, "bin", "*"), File.join(libd, "**", "*.{dylib,so}")].select { |f| macho?(f) }
    queue = seeds.dup
    seen = {}
    until queue.empty?
      f = queue.shift
      next if seen[f]

      seen[f] = true
      otool_refs(f).each_with_index do |ref, i|
        next if i.zero? && dylibish.call(f) # install name, not a dependency

        case ref
        when MACOS_SYSTEM_REF
          system_refs[ref] = true
        when MACOS_SUPPLIER_REF
          leaf = File.basename(ref)
          die("absolute ref to missing supplier lib: #{ref} (referenced by #{f})") unless File.exist?(ref)
          real = File.realpath(ref)
          dest = File.join(libd, leaf)
          if copied.key?(leaf)
            warn("closure leaf #{leaf} also referenced as #{ref}") unless copied[leaf] == real
          elsif File.exist?(dest)
            if FileUtils.compare_file(dest, real)
              copied[leaf] = real # identical copy from a previous run — re-walked via seeds
            else
              # payload's own lib with the same leaf (e.g. lib2geom) — single
              # supplier makes this a hard error: two different dylibs, one name
              die("closure leaf collision: #{ref} vs payload's own #{dest}")
            end
          else
            FileUtils.cp(real, dest)
            FileUtils.chmod(0o755, dest) # brew bottles are read-only (0444);
                                         # strip/install_name_tool/codesign need +w
            copied[leaf] = real
            queue << dest if macho?(dest)
          end
        when /\A@rpath\/(.+)/
          leaf = Regexp.last_match(1)
          next if payload_leaf.call(leaf) || copied.key?(leaf)
          die("unresolvable @rpath ref #{ref} in #{f} (not in payload, not a supplier lib)")
        when /\A(@loader_path|@executable_path)\//
          next # intra-payload reference, resolved relative to its loader
        else
          die("unexpected dylib ref form #{ref} in #{f}")
        end
      end
    end

    # rewrite pass: supplier-absolute refs -> @rpath/<leaf>, ids -> @rpath/<leaf>
    edited = Dir[File.join(root, "bin", "*"), File.join(libd, "**", "*.{dylib,so}")].select { |f| macho?(f) }
    edited.each do |f|
      args = []
      otool_refs(f).each_with_index do |ref, i|
        if i.zero? && dylibish.call(f)
          args += ["-id", "@rpath/#{File.basename(f)}"] if ref.match?(MACOS_SUPPLIER_REF)
          next
        end
        args += ["-change", ref, "@rpath/#{File.basename(ref)}"] if ref.match?(MACOS_SUPPLIER_REF)
      end
      sh("install_name_tool", *args, f, quiet: true) unless args.empty?
    end

    # verification pass: nothing outside system + @rpath/payload may remain
    leaks = []
    edited.each do |f|
      otool_refs(f).each_with_index do |ref, i|
        next if i.zero? && dylibish.call(f) # install name, not a dependency
        next if ref.match?(MACOS_SYSTEM_REF) || ref.start_with?("@loader_path/", "@executable_path/")
        if (m = ref.match(/\A@rpath\/(.+)/))
          leaf = m[1]
          leaks << "#{f}: unresolved @rpath/#{leaf}" unless payload_leaf.call(leaf) || copied.key?(leaf)
        else
          leaks << "#{f}: #{ref}"
        end
      end
    end
    die("macOS closure leaks (non-system refs outside the payload):\n  #{leaks.join("\n  ")}") unless leaks.empty?
    File.write(stamp, copied.keys.sort.join("\n") + "\n") if stamp
    log("macOS closure: #{copied.size} supplier libs, #{system_refs.size} system refs excluded")
    copied
  end

  # ad-hoc re-sign every Mach-O in the tree. Mandatory on arm64 after
  # install_name_tool / strip (both invalidate the link-time ad-hoc
  # signature; unsigned arm64 binaries are killed at exec).
  def codesign_tree(root)
    files = Dir[File.join(root, "**", "*")].select { |f| macho?(f) }
    files.each { |f| sh("codesign", "--force", "--sign", "-", f, quiet: true) }
    log("codesign: ad-hoc re-signed #{files.size} Mach-O files")
  end

  def brew_prefix(formula)
    args = ["brew", "--prefix", *(formula ? [formula] : [])]
    out, ok = capture(*args)
    ok ? out.strip : nil
  end
end
