cmake_minimum_required(VERSION 2.8)
project(encrypt)

find_library(cloudhsmpkcs11 STATIC)

add_executable(aes_cbc aes_cbc.c aes.c)
add_executable(aes_cbc_enc aes_cbc_enc.c aes.c)
add_executable(aes_cbc_dec aes_cbc_dec.c aes.c)

target_link_libraries(aes_cbc cloudhsmpkcs11)
target_link_libraries(aes_cbc_enc cloudhsmpkcs11)
target_link_libraries(aes_cbc_dec cloudhsmpkcs11)

add_test(aes_cbc aes_cbc --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(aes_cbc_enc aes_cbc_enc --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(aes_cbc_dec aes_cbc_dec --pin ${HSM_USER}:${HSM_PASSWORD})

