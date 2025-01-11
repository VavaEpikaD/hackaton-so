### Lambda-function-loader
by Vlad-Raul Vasile and Belciug Matei
* We have input multiplexing
* We didn't use prehooks or posthooks
* In lib_load we laod the libraries and the function from the memory
* In lib_execute we fork the current process and execute the given command in the child
* In lib_close we unload the library
* In main we create the socket for the connection with the clients and then we accept the client requests
* The requests are parsed with the given method parse_command and then the command is executed
* On error, lib_run returns -1 which is used in the main loop to output an error message in the output file
* Lastly, the output file is returned to the client
* After the main loop we free the memory used
* The first 6 tests pass
* We tried using epoll for the 7th test

* github link: https://github.com/VavaEpikaD/hackaton-so