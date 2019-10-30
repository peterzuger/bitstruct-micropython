# bitstruct-micropython

## Table of Contents
+ [About](#about)
+ [Getting Started](#getting_started)
+ [Usage](#usage)
+ [module documentation](https://bitstruct.readthedocs.io/en/latest/)

## About <a name = "about"></a>
This is a port of [eerimoq/bitstruct](https://github.com/eerimoq/bitstruct) for
[micropython](https://github.com/micropython/micropython)

## Getting Started <a name = "getting_started"></a>

### Prerequisites
This port of [eerimoq/bitstruct](https://github.com/eerimoq/bitstruct) is designed for
[micropython](https://github.com/micropython/micropython)

```
git clone --recurse-submodules https://github.com/micropython/micropython.git
```

to compile the project, [make](https://www.gnu.org/software/make/),
[gcc](https://gcc.gnu.org/) and [arm-none-eabi-gcc](https://gcc.gnu.org/) is required,
install them from your package manager

### Installing
[bitstruct-micropython](https://github.com/peterzuger/bitstruct-micropython) should work on
any [micropython](https://github.com/micropython/micropython) port.

First create a modules folder next to your copy of [micropython](https://github.com/micropython/micropython).

```
project/
├── modules/
│   └──bitstruct-micropython/
│       ├──...
│       └──micropython.mk
└── micropython/
    ├──ports/
   ... ├──stm32/
      ...
```

And now put this project in the modules folder.

```
cd modules
git clone https://gitlab.com/peterzuger/bitstruct-micropython.git
```

Now that all required changes are made, it is time to build [micropython](https://github.com/micropython/micropython),
for this cd to the top level directory of [micropython](https://github.com/micropython/micropython).
From here, first the mpy-cross compiler has to be built:
```
make -C mpy-cross
```

once this is built, compile your port with:
```
make -C ports/your port name here/ USER_C_MODULES=../modules CFLAGS_EXTRA=-DMODULE_BITSTRUCT_ENABLED=1
```

and you are ready to use bitstruct.

## Usage <a name = "usage"></a>
The module is available by just importing bitstruct:
```
import bitstruct
```

The module documentation is available here: [Documentation](https://bitstruct.readthedocs.io/en/latest/).
Keep in mind that this C port is Work in progress, while most features are working,
there are still a few missing things most notably the missing kwarg support,
this is one of the next things on the todo list.
