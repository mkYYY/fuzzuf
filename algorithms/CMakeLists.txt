afl_common_is_required( enable_afl_common "${ALGORITHMS}" )
if( enable_afl_common )
  add_subdirectory(
    afl_common
  ) 
endif()
libfuzzer_common_is_required( enable_libfuzzer_common "${ALGORITHMS}" )
if( enable_libfuzzer_common )
  add_subdirectory(
    libfuzzer_common
  ) 
endif()
set( FUZZUF_ALGORITHM_LIBS "" )
foreach( alg ${ALGORITHMS} )
  if( EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${alg} )
    if( IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${alg} )
    add_subdirectory(
      ${alg}
    ) 
    endif()
  endif()
  if( TARGET "fuzzuf_core_${alg}" )
    list(APPEND FUZZUF_ALGORITHM_LIBS "fuzzuf_core_${alg}" )
  endif()
endforeach()
set( FUZZUF_ALGORITHM_LIBS "${FUZZUF_ALGORITHM_LIBS}" PARENT_SCOPE )

