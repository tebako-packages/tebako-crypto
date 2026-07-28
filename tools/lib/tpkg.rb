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

  # Clone a git repo at a pinned commit and verify HEAD matches the pin.
  # A commit pin authenticates the whole tree; used where upstream ships no
  # release tarball to sha256 (vcpkg, dwarfs-t).
  def git_pinned(git_url, commit, dest)
    if !File.directory?(File.join(dest, ".git"))
      sh("git", "clone", "--filter=blob:none", git_url, dest)
    end
    unless system("git", "-C", dest, "cat-file", "-e", "#{commit}^{commit}")
      sh("git", "fetch", "--quiet", "origin", commit, chdir: dest)
    end
    sh("git", "checkout", "--quiet", commit, chdir: dest)
    head, = capture("git", "rev-parse", "HEAD", chdir: dest)
    # normalize: a pin may name an annotated tag object; compare commits
    want, = capture("git", "rev-parse", "#{commit}^{commit}", chdir: dest)
    die("pin mismatch in #{dest}: HEAD=#{head.strip}, want #{want.strip}") unless head.strip == want.strip
    dest
  end

  def cache_dir
    dir = ENV.fetch("TPKG_CACHE", File.join(ROOT, ".cache"))
    FileUtils.mkdir_p(dir)
    dir
  end

  # Locate or obtain the image tools (mkdwarfs + a mount/extract helper).
  # Order: $MKDWARFS env → libtfs release assets (macOS legs) → tool cache →
  # pinned dwarfs-t source build (linux legs; no published dwarfs-t releases
  # exist — see build-notes). The macOS legs use tamatebako/libtfs release
  # binaries (sha256-pinned in recipe image.libtfs): dwarfs-t has no macOS
  # releases and building it on macOS is untested, while libtfs ships a
  # static mkdwarfs plus tebakofs (multi-backend CLI; `tebakofs extract`
  # replaces dwarfsextract for the FUSE-less degraded boot-smoke).
  def ensure_dwarfs_tools(recipe, platform: nil)
    if ENV["MKDWARFS"] && File.executable?(ENV["MKDWARFS"])
      log("using $MKDWARFS=#{ENV['MKDWARFS']}")
      return { "mkdwarfs" => ENV["MKDWARFS"],
               "dwarfs" => ENV["DWARFS"],
               "dwarfsextract" => ENV["DWARFSEXTRACT"],
               "tebakofs" => ENV["TEBAKOFS"] }.compact
    end

    if platform&.end_with?("-macos")
      spec = recipe.fetch("image").fetch("libtfs")
      arch = { "aarch64-macos" => "arm64", "x86_64-macos" => "x86_64" }.fetch(platform)
      dir = File.join(cache_dir, "tools", "libtfs-#{spec['release']}")
      FileUtils.mkdir_p(dir)
      tools = {}
      %w[mkdwarfs tebakofs].each do |t|
        asset = "#{t}-macos-#{arch}"
        want = spec.fetch("sha256").fetch(asset)
        bin = Tpkg.fetch("https://github.com/tamatebako/libtfs/releases/download/#{spec['release']}/#{asset}",
                         File.join(dir, asset), want)
        FileUtils.chmod(0o755, bin)
        tools[t] = bin
      end
      return tools
    end

    pin = recipe.fetch("image").fetch("dwarfs_t")
    dest = File.join(cache_dir, "dwarfs-t", pin["commit"])
    bindir = File.join(dest, "bin")
    mkdwarfs = File.join(bindir, "mkdwarfs")
    unless File.executable?(mkdwarfs)
      # dwarfs-t manpage codegen needs python mistletoe; ubuntu-24.04's
      # PEP 668 blocks plain `pip3 install` (externally-managed-environment)
      have_mistletoe = -> { system("python3", "-c", "import mistletoe", %i[out err] => File::NULL) }
      unless have_mistletoe.call
        sudo = Process.uid.zero? ? [] : ["sudo"]
        system(*sudo, "apt-get", "install", "-y", "-qq", "python3-mistletoe") if system("command -v apt-get >/dev/null 2>&1")
        unless have_mistletoe.call
          system("pip3", "install", "--break-system-packages", "mistletoe") ||
            system("pip3", "install", "--user", "mistletoe") ||
            die("could not install python mistletoe (dwarfs-t manpage codegen needs it)")
        end
      end
      log("building mkdwarfs-t from pinned source #{pin['commit'][0, 12]}… (no published releases)")
      src = git_pinned(pin["git"], pin["commit"], File.join(dest, "src"))
      triplet = ENV.fetch("TPKG_DWARFS_TRIPLET", "x64-linux")
      build = File.join(dest, "build")
      sh("cmake", "-S", src, "-B", build, "-G", "Ninja",
         "-DCMAKE_BUILD_TYPE=Release",
         "-DCMAKE_TOOLCHAIN_FILE=#{File.join(vcpkg_root_for(recipe), 'scripts/buildsystems/vcpkg.cmake')}",
         "-DVCPKG_TARGET_TRIPLET=#{triplet}",
         "-DVCPKG_MANIFEST_FEATURES=",
         "-DVCPKG_OVERLAY_PORTS=#{File.join(src, 'vcpkg_ports')}",
         "-DWITH_TOOLS=ON", "-DWITH_LIBDWARFS=ON", "-DWITH_TESTS=OFF", "-DWITH_BENCHMARKS=OFF")
      sh("cmake", "--build", build, "--parallel", "4", "--target", "mkdwarfs", "dwarfs", "dwarfsextract")
      FileUtils.mkdir_p(bindir)
      %w[mkdwarfs dwarfs dwarfsextract].each do |t|
        found = Dir[File.join(build, "**", t)].find { |f| File.executable?(f) && !File.directory?(f) }
        die("built #{t} not found under #{build}") unless found
        FileUtils.cp(found, bindir)
      end
    end
    { "mkdwarfs" => File.join(bindir, "mkdwarfs"),
      "dwarfs" => File.join(bindir, "dwarfs"),
      "dwarfsextract" => File.join(bindir, "dwarfsextract") }
  end

  # vcpkg checkout used for the inkscape deps. dwarfs-t's own manifest pins a
  # different baseline; its build resolves that itself through this root when
  # TPKG_DWARFS_VCPKG is unset. Kept simple: one vcpkg checkout per recipe.
  def vcpkg_root_for(recipe)
    spec = recipe.dig("build", "vcpkg") or die("recipe has no build.vcpkg section")
    git_pinned(spec["git"], spec["commit"], File.join(cache_dir, "vcpkg"))
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
