project(
    'salty-stun',
    'c',
    version: '0.1.0',
    meson_version: '>=1.3',
    default_options: ['c_std=c11', 'warning_level=3', 'b_ndebug=if-release'],
)
add_project_arguments('-D_DEFAULT_SOURCE', language: 'c')

cc = meson.get_compiler('c')

add_project_arguments(
    cc.get_supported_arguments(
        [
            '-Wundef',
            '-Wmissing-include-dirs',
            '-Wold-style-definition',
            '-Wstrict-prototypes',
            '-Wmissing-prototypes',
            '-Walloca',
            '-Wshadow',
            '-Wcast-qual',
            '-Wswitch-default',
            '-Wswitch-enum',
            '-Wredundant-decls',
            '-Wundef',
            '-Wnested-externs',
        ],
    ),
    language: 'c',
)

fs = import('fs')

# Strip relative path prefixes
relative_dir = fs.relative_to(
    meson.current_source_dir(),
    meson.global_build_root(),
) + '/'
if cc.has_argument('-fmacro-prefix-map=/prefix/to/hide=')
    add_project_arguments(
        '-fmacro-prefix-map=@0@='.format(relative_dir),
        language: 'c',
    )
endif

sodium_dep = dependency('libsodium')
blake2_dep = dependency('libb2')

version_data = configuration_data()
version_data.set_quoted('SALTY_STUN_VERSION', meson.project_version())
configure_file(output: 'version.h', configuration: version_data)
config_dir = include_directories('.')

salty_stun_dep = declare_dependency(
    sources: [
        'src/args.c',
        'src/main.c',
        'src/log.c',
        'src/wireguard/hash.c',
        'src/wireguard/hmac.c',
        'src/wireguard/kdf.c',
        'src/wireguard/wireguard.c',
        'src/wireguard/state_mem.c',
        'src/inet/ip.c',
        'src/inet/icmp.c',
        'src/inet/checksum.c',
        'src/inet/udp.c',
        'src/stun/stun.c',
        'lib/cdsa/hashtable.c',
    ],
    include_directories: ['src', config_dir, 'lib'],
    dependencies: [sodium_dep, blake2_dep],
)

salty_stun_exe = executable(
    'salty-stun',
    install: true,
    dependencies: [salty_stun_dep],
)

pytest = find_program('pytest', required: get_option('tests'))
if pytest.found()
    salty_stun_test_exe = executable(
        'salty-stun-test',
        dependencies: [salty_stun_dep],
        c_args: ['-DTEST'],
    )

    test_log_exe = executable(
        'test-log',
        'src/log.c',
        'tests/test_log.c',
        include_directories: ['src'],
    )

    test(
        'salty-stun-test',
        pytest,
        args: ['--exitfirst', '--builddir=' + meson.current_build_dir()],
        depends: [salty_stun_test_exe, test_log_exe],
        workdir: meson.current_source_dir(),
    )
endif

scdoc = find_program('scdoc', required: get_option('docs'))
if scdoc.found()
    manpage = custom_target(
        'salty-stun.1',
        input: 'salty-stun.1.scd',
        output: 'salty-stun.1',
        command: ['scdoc'],
        feed: true,
        capture: true,
        install: true,
        install_dir: get_option('mandir') / 'man1',
    )
endif
