#!/bin/bash

valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all src/chatd $(/labs/tsam15/my_port) 
