project(
    'salty-stun',
    'c',
    version: '0.1',
    meson_version: '>=1.3',
    default_options: ['c_std=c11', 'warning_level=3'],
)
add_project_arguments('-D_DEFAULT_SOURCE', language: 'c')

cc = meson.get_compiler('c')
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

exe = executable(
    'salty-stun',
    sources: [
        'src/main.c',
        'src/log.c',
        'src/wireguard/hash.c',
        'src/wireguard/hmac.c',
        'src/wireguard/kdf.c',
        'src/wireguard/wireguard.c',
        'src/inet/ip.c',
        'src/inet/icmp.c',
        'src/inet/checksum.c',
        'src/inet/udp.c',
        'src/stun/stun.c',
    ],
    include_directories: 'src',
    install: true,
    dependencies: [sodium_dep, blake2_dep],
)
