add_library(generateInput MODULE
        generateInput.cpp
        )

set_target_properties(generateInput PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )