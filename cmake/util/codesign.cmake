find_program(CODESIGN_COMMAND codesign REQUIRED)

function(codesign_sign_files files signature keychain)
    if (NOT signature)
        message(FATAL_ERROR "codesign failed: signature is required")
    endif()

    set(args
        --force
        --verbose
        --sign "${signature}"
    )
    # personal builds are signed ad-hoc ("-") or with a self-signed certificate (CODESIGN_PLAIN):
    # no timestamp, and no hardened runtime, whose library validation needs an Apple Team ID
    if(NOT signature STREQUAL "-" AND NOT "$ENV{CODESIGN_PLAIN}")
        list(APPEND args --timestamp --options runtime)
    endif()

    if(keychain)
        list(APPEND args --keychain "${keychain}")
    endif()

    foreach(file IN LISTS files)
        set(cmd ${CODESIGN_COMMAND} ${args} "${file}")

        list(JOIN cmd " " cmd_str)
        message(STATUS "${cmd_str}")

        execute_process(
            COMMAND ${cmd}
            RESULT_VARIABLE result
            ERROR_VARIABLE error
        )
        if(NOT result EQUAL 0)
            string(REPLACE "\n" "\n  " error "  ${error}")
            message(FATAL_ERROR "codesign failed:\n${error}")
        endif()
    endforeach()
endfunction()
