option(USE_ED25519_AMD64_RADIX_64_24K_OPTIMIZATION
       "Using radix 2^64 and a 24KB precomputed table optimization for ed25519 curves on the x86_64 processor." OFF)
option(USE_ED25519_AMD64_RADIX_51_30K_OPTIMIZATION
       "Using radix 2^51 and a 30KB precomputed table optimization for ed25519 curves on the x86_64 processor." OFF)

add_subdirectory(common)

# Define src_ed25519
if (USE_ED25519_AMD64_RADIX_64_24K_OPTIMIZATION)
    add_subdirectory(amd64_64_24k)
elseif(USE_ED25519_AMD64_RADIX_51_30K_OPTIMIZATION)
    add_subdirectory(amd64_51_30k)
else ()
    add_subdirectory(ref10)
endif ()

set(src_ed25519 "${src_ed25519_common}" "${src_ed25519_impl}" CACHE INTERNAL "")
