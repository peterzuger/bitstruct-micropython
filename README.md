# bitstruct-micropython

## Table of Contents
+ [About](#about)
+ [Getting Started](#getting_started)
+ [Usage](#usage)
+ [module documentation](https://bitstruct.readthedocs.io/en/latest/)

## About <a name = "about"></a>
This is a port of [eerimoq/bitstruct][1] for [micropython][2]

## Getting Started <a name = "getting_started"></a>

### Prerequisites
This port of [eerimoq/bitstruct][1] is designed for [micropython][2]

```
git clone --recurse-submodules https://github.com/micropython/micropython.git
```

to compile the project, [make][4],
[gcc][5] and [arm-none-eabi-gcc][5] is required,
install them from your package manager

### Installing
[bitstruct-micropython][0] should work on any micropython port,
to make the required changes, move to the directory of your required port.

The first step of the installation is to move this project to the folder of your port.

Then it is required to tell the micropython build system about the
source files, to do this, append the following lines to

```
mpconfigport.mk
```

```
SRC_MOD += bitstruct-micropython/bitstruct/bitstream.c
SRC_MOD += bitstruct-micropython/bitstruct/bitstruct.c
```

now the files get compiled, but the bitstruct module is not added to
the micropython binary, to do this one more change is required.

both changes are in:

```
mpconfigport.h
```

first tell the compiler that you defined ```mp_module_bitstruct```, there
are usualy a few more of these for other builtin modules, place this after these.
```
extern const struct _mp_obj_module_t mp_module_bitstruct;
```

then you need to add the bitstruct module to the ```MICROPY_PORT_BUILTIN_MODULES``` define
to do this just append this line at the end of the ones that are already there.
here it is important to not leave an empty line between the last one an this one,
since that would end the macro prematurely.
```
{ MP_OBJ_NEW_QSTR(MP_QSTR_bitstruct), (mp_obj_t)&mp_module_bitstruct }, \
```

Now that all required changes are made, it is time to build micropython,
for this cd to the top level directory.
From here, first the mpy-cross compiler has to be built:
```
make -C mpy-cross
```

once this is built, compile your port with:
```
make -C ports/your port name here/
```

and you are ready to use bitstruct.

## Usage <a name = "usage"></a>
The module is available by just importing bitstruct:
```
import bitstruct
```

The module documentation is available here: [Documentation][3].
Keep in mind that this C port is Work in progress, while most features are working,
there are still a few missing things most notably the missing kwarg support,
this is one of the next things on the todo list.

[0]:(https://github.com/peterzuger/bitstruct-micropython)
[1]:(https://github.com/eerimoq/bitstruct)
[2]:(https://github.com/eerimoq/bitstruct)
[3]:(https://bitstruct.readthedocs.io/en/latest/)
[4]:(https://www.gnu.org/software/make/)
[5]:(https://gcc.gnu.org/)
