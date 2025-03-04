#!/bin/bash
while getopts "r:" opt
do
    case "${opt}" in
    r) num=${OPTARG};
    ;;
    esac
done


# if [ "$num" -gt 0 ]
# then
    for i in $(seq 1 8)
    do
        if [ "$i" -eq 1 ]
        then
            cmd="AFL_NO_STARTUP_CALIBRATION=1 ./afl-fuzz -M fuzzer${i} $@ ; read -p 'Press enter to exit!'";
            x-terminal-emulator -e /bin/bash -c "$cmd" &
        else
            cmd="AFL_NO_STARTUP_CALIBRATION=1 ./afl-fuzz -S fuzzer${i} $@ ; read -p 'Press enter to exit!'";
            x-terminal-emulator -e /bin/bash -c "$cmd" &
        fi
        sleep 1;
    done
# else
#    echo "Failed";
# fi
