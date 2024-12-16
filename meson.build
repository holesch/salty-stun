project(
    'salty-stun',
    'c',
    version: '0.1',
    default_options: ['c_std=c11', 'warning_level=3'],
)
add_project_arguments('-D_DEFAULT_SOURCE', language: 'c')

sodium_dep = dependency('libsodium')
blake2_dep = dependency('libb2')

exe = executable(
    'salty-stun',
    sources: [
        'src/main.c',
        'src/wireguard/hash.c',
        'src/wireguard/hmac.c',
        'src/wireguard/kdf.c',
        'src/wireguard/wireguard.c',
        'src/inet/ip.c',
        'src/inet/icmp.c',
        'src/inet/checksum.c',
    ],
    include_directories: 'src',
    install: true,
    dependencies: [sodium_dep, blake2_dep],
)
