#!/bin/bash

valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all src/chatd $(/labs/tsam15/my_port) /home/hir.is/eysteinn13/Tolvusamskipti/tsam15/pa3/src/fd.crt /home/hir.is/eysteinn13/Tolvusamskipti/tsam15/pa3/src/fd.key /home/hir.is/eysteinn13/Tolvusamskipti/tsam15/pa3/src/CAfile.pem
