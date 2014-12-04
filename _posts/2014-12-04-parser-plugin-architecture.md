---
layout: post
title: BAP Executable Format Parsers
---

One of the fundamental tasks in binary analysis is parsing executable
formats on disk.  Popular executable formats include ELF (Linux),
Mach-O (OS X), and PE (Windows). In IDA Pro, this parsing is done by
what they call loaders.

When designing the BAP architecture, we had two goals:

1. Enable the use of existing and third-party parsing libraries.
2. Provide a unified front-end view and set of routines to downstream
   code that is agnostic to the particular parsing format.

Our approach to meeting these goals was to design a plugin
architecture. The plugin architecture consists of two logical pieces
of code:


1. A parser-specific backend plugin that presents a simplified view on
   data stored in a particular binary container. This representation
   is minimized and simplified, in order to make it easier to write
   plugins in languages other then OCaml. The representation is
   described in a
   [`Image_backend`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap_image/image_backend.ml)
   module.

2. A frontend module
   [`Image`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap_image/bap_image.ml)
   that provides access to the data in executable container formats
   while abstracting away the specific details of that
   container. Example functions include creating an `image` from a
   filename or data string, getting attributes such as the
   architecture and address size, etc. And, of course, it provides
   methods to access the actual data, like sections, symbols and
   memory.



*Aside: Namespace management*

In the rest of this article we go through the plugin architecture
using the ocaml-native ELF plugin as our running example.

We assume, that BAP namespace is opened, i.e., that there is

{% highlight ocaml  %}
utop # open Bap.Std;;
{% endhighlight %}


Also we will refer to all definitions using their short aliases. If it
is no stated otherwise, all types and definitions are belong to a
`Bap.Std` namespace.

Underneath the hood we use somewhat mangled names, to overcome some
problems with linking and `ocamlfind`, and to preserve namespace
purity. But this is hidden from our users, so you should never use or
refer to a module prefixed with `Bap_something`, this only for
internals. Actually, the structure mimics OCaml `Core` library quite
closely, so there is nothing new here.

*Aside: OCaml Hints*

BAP comes with a program called `baptop`, which is a `utop` interface
that loads the BAP.  `utop` provides a bunch of useful directives,
that can help you to explore BAP library interactively.  You can find
the type of any type, module or expression or in `baptop` by using the
`#typeof` directive followed by the name of the expression in
quotes. For example, to find the type of `Image.t`, in `baptop` type:

{% highlight ocaml  %}
(* using a fully-qualified name.  *)
utop # #typeof "image";;
type Bap.Std.image = Bap.Std.Image.t
{% endhighlight %}

## Parsing

Bap contains separate libraries that parses files containing Elf and
Dwarf data. Elf parser is implemented in a
[`Elf`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap_elf/bap_elf.ml)
module. [`Elf.Types`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap_elf/elf_types.ml)
submodule exposes a rich set of type
definitions. [`Elf.Parse`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap_elf/elf_parse.ml)
provides an interface to the parser.

The parser is written in a non-intrusive way, i.e., it tries not to
perform unnecessary copies of data, and will provide only offsets in a
file, instead of actually the data. That is the reason why we've
reimplemented it from the original library, written by by Jyun-Yan
You. Of course, there're utility functions `Elf.section_name` and
`Elf.string_of_section` to help you to retrieve data from an
underlying file.

*Aside: Error handling*

Functions in BAP do not occasionally throw exceptions. Instead, if
function can fail, then it will specify it explicitly in its type, by
returning a value of type
[`'a Or_error.t`](https://blogs.janestreet.com/ocaml-core/110.01.00/doc/core_kernel/#Or_error),
that is described in their
[blog](https://blogs.janestreet.com/how-to-fail-introducing-or-error-dot-t/)
as well as in the Real World Ocaml
[Chapter 7](https://realworldocaml.org/v1/en/html/error-handling.html).

## Backend Plugin

Actual Elf plugin, that we're currently using, is implemented on top
of two libraries: `bap.elf` described earlier, and `bap.dwarf` that
allows one to lookup dwarf symbols in a file. At the time of this
writing, our elf parsing library doesn't support symtables reading.

The ELF backend code's job is to abstract away the ELF and DWARF
specific details into a unified `image` type.

*Aside: Bap plugin system*

Bap library can be non-intrusively extended by using our own plugin
system. A plugin is an OCaml library that is installed in the system
in the place, where `ocamlfind` tool can find it. The `META` file,
that describes the library should contain a string:

```
plugin_system = "bap.subsystem"
```

Where `subsystem` stands to a name of subsystem of BAP that you would
like to extend. For example, if you're adding new image backend, then
it should be, `image`:

```
plugin_system = "bap.image"
```

If, you're adding a new disassembler, then it should be a `disasm`, like

```
plugin_system = "bap.disasm"
```

All plugins are loaded with `Plugins.load` command. When plugin is
loaded, all it code is evaluated. The actual registration of the
plugin service is specific to each subsystem. But usually it includes
some kind of registration, like calling `Image.register_backend` for
the plugins of `bap.image` system.

Note 1: `baptop` will automatically load plugins for you.

Note 2: `Plugins.load` function shouldn't be called from a `baptop`
since, toplevels in OCaml have different linking rules.

Note 3: It is not possible to re-evaluate plugin after you have
changed and reinstalled it. The only way is to restart the program, or
`baptop`.

Note 4: Plugin system will check, that the plugin is compiled against
the same interfaces as the main program. So, if you have updated and
recompiled bap, or updated systems library that we're depend on, then
make sure, that you also reinstall your plugins. Otherwise, they won't
load.

If you're writing your own plugin, then I would suggest you, to use
`oasis` tool, to generate all the necessary files and scripts for
you. A minimum oasis file would be:

```
OASISFormat: 0.4
Name:        bap
Version:     0.2
Synopsis:    BAP Core Library
Authors:     Plugin Writers
License:     MIT
Copyrights:  (C) 2014 Carnegie Mellon University
Plugins:     META (0.4), DevFiles (0.4)
BuildTools: ocamlbuild, camlp4o

Library elf_backend
  Path:            .
  FindlibName:     our_fancy_bap_plugin
  XMETAExtraLines: plugin_system = "bap.image"
  CompiledObject:  best
  BuildDepends:    bap
  Modules:         A, B, C
```

A detailed interface to plugin system is provided in
[`Plugin`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap/bap_plugin.ml)
and
[`Plugins`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap/bap_plugins.ml)modules. For
example, you can look at all available plugins with this command
(assuming that `Core_kernel.Std` is opened):

{% highlight ocaml %}
# Plugins.all () |> List.map ~f:Plugin.name;;
- : bytes list = ["bap.image.elf_backend"]
{% endhighlight %}

## Frontend

The frontend provides an abstraction over executables formats, and is
agnostic to the particular backend.  You shouldn't have to do anything
here, and your users can now use the various
[`Image`](https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap_image/bap_image.ml)
functions and data structures such as finding entry points
(`Image.entry_point`), architecture (`Image.arch`), and so on.

## Summary

BAP provides a neat plugin architecture for adding new backends that
parse executable formats.  In order to support a new format, you
should write (or find an existing) parser, and then write a small
set of functions as a plugin that translate whatever the parser code
outputs into the BAP data structures.  Our plugin system allows third
parties to add plugins at any time without changing BAP.  The plugin
system also means end users do not have to change any of their code
when a new plugin is added.


One elephant in the room we did not address is why we do not simply
use BFD, as we did in previous versions of BAP.  One reason is BFD is
a large library, and therefore may be more than most people
need. While a large library may seem attractive at first blush (after
all, features!), remember that if you get the functionality, you also
get all the bugs, vulnerabilities, and support issues as well.  A
second reason is BFD is GPL, which would mean BAP is GPL if we
included it as a core component.  GPL poses a barrier for adoption in
some practical scenarios, which we wish to avoid.

Overall, by abstracting to a plugin architecture in this release of
BAP, we believe we hit a nice middleground where people can use
whatever backends they want for parsing, while providing a useful set
of features to front-end users.
