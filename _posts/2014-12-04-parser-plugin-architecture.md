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
architecture. The plugin architecture consists of three logical pieces
of code:

1. The executable container format parser. This can be third-party
   code and can be written in any language. The parser should take in
   an optional starting offset to begin parsing, an optional length
   parameter, and the bitstring of the raw file (e.g., as it appears
   on disk).  The function should return a parsed executable image.
   
2. A parser-specific backend plugin that translates the parsed
   structure into the BAP data types for executables. The datatypes
   are that of a section (`Bap.Std.Image.Sec.t`) and symbols
   (`Bap.Std.Image.Sym.t`).  The parser must also register itself by
   calling `Bap.Std.Image.register_backend`.
   
3. A frontend that provides access to the data in executable container
   formats while abstracting away the specific details of that
   container.  These functions are generally available in the `Bap.Std.Image`
   namespace.  Example functions include creating a `Bap.Std.Image.t` from a
   filename, creating an `Bap.Std.Image.t` from a string, getting attributes
   of an image such as the architecture and address size, etc.



*Namespace management*
In the rest of this article we go through the plugin architecture
using the ocaml-native ELF plugin as our running example. Note that
sometimes we refer to specific filenames as a guide, but the specific
filenames are subject to change.  The overall module namespace is not,
so you should always be able to find the specific files by following
the namespace conventions.

Recall that in OCaml the filename serves as a default module name. In
order to keep a tidy namespace, we have created namespace aliases. For
example, currently we have a file called `bap_elf.ml`, which looks like:

{% highlight ocaml  %}
module Types = Elf_types
module Parse = Elf_parse
type t = Types.elf
include Elf_utils
{% endhighlight %}

The purpose of `bap_elf.ml` is to help with namespace
management. Everything in this file will be referred to under
`Bap.Std.Elf`, as per the oasis file.  In this file, we say that the
filename (and by default module name `Elf_types` from `elf_types.ml`)
will be known as `Types` (fully qualified as `Bap.Std.Elf.Types`).
Similarly `Elf_parse` is given the namsapce `Parse`. This way if we
ever change the name of the actual file (e.g., we rename
`elf_types.ml` to `really_cool_elf.ml`) the name visible to the user
stays the same.

*OCaml Hints*
BAP comes with a program called `baptop`, which is a `utop` interface
that loads the BAP.  You can find the type of any
function or type in `baptop` by using the `#typeof` directive followed
by the name of the function or type in quotes. For
example, to find the type of `Image.t`, in `baptop` type:

{% highlight ocaml  %}
(* using a fully-qualified name.  *)
utop # #typeof "Bap.Std.Image.t";;
type Bap.Std.Image.t = Bap_image.t
{% endhighlight %}

Also, for simplicity in the rest of this post we leave off the
`Bap.Std` prefix in the namespace.  In `baptop` you can follow along
without fully qualifying the namespace by simply opening `Bap.Std`:

{% highlight ocaml  %}
utop # open Bap.Std;;
{% endhighlight %}



## Parsing

The first step when given an executable image is to parse it. In BAP,
our parser is currently located in `Bap.Std.Elf.Parse` namespace.  The
actual files are in the `bap/lib/bap_elf` directory.  The files are
lightly adapted from an ELF parser originally written by Jyun-Yan You,
and you will find his original copyright still available.

Our ELF parser exposes one function:

{% highlight ocaml  %}
val from_bigstring : ?pos:int -> ?len:int ->  Bigstring.t -> elf Or_error.t
{% endhighlight %}



The `from_bigstring` function takes in an optional position `pos` and
optional length `len` parameter, a mandatory bitstring (the file), and
returns an `elf Or_error.t`.  The `elf Or_error.t` polymorphic type is
defined in Jane Street Core and described in their
[blog](https://blogs.janestreet.com/how-to-fail-introducing-or-error-dot-t/)
as well as in the Real World Ocaml
[Chapter 7](https://realworldocaml.org/v1/en/html/error-handling.html). The
type returns either something of type `elf`, or an error. The `elf`
type itself is defined in `elf_types.ml`.

Internally, `from_bigstring` parses the input `bigstring.t` into a
`Elf.Types.Elf.t` record:


{% highlight ocaml %}
utop # #typeof "Bap.Std.Elf.t";;
type Bap.Std.Elf.t = Bap.Std.Elf.Types.elf
utop # #typeof "Bap.Std.Elf.Types.elf";;
type Bap.Std.Elf.Types.elf =                                                      Elf_types.elf = {
    e_class : Bap.Std.Elf.Types.e_class;
    e_data : Bap.Std.Elf.Types.e_data;
    e_version : int;
    e_osabi : Bap.Std.Elf.Types.e_osabi;
    e_abiver : int;
    e_type : Bap.Std.Elf.Types.e_type;
    e_machine : Bap.Std.Elf.Types.e_machine;
    e_entry : int64;
    e_shstrndx : int;
    e_sections : Bap.Std.Elf.Types.section Core_kernel.Std.Sequence.t;
    e_segments : Bap.Std.Elf.Types.segment Core_kernel.Std.Sequence.t;
  }
{% endhighlight %}


## Backend Plugin

The ELF backend code's job is to abstract away the ELF-specific
details into a unified `Image.t` type.  We implement this by creating
a plugin.

In order to implement plugins, we use a neat trick. OCaml evaluates
any top-level statement  when a module is linked or loaded.  For
example, many OCaml users have used a `let () = ...` as the equivalent
of `main` in a program.  We create a statement in the ELF plugin that
registers itself as a module:

{% highlight ocaml %}
let () =
  let r =
    Bap_image.register_backend ~name of_data in
  match r with
  | `Ok -> ()
  | `Duplicate ->
  eprintf "Elf_backend: name «%s» is already used\n" name
{% endhighlight %}

Since this statement will be evaluated on link or load, we will always
register ourself as a plugin.  During build, we tell the opam
installer to include us as part of the `bap.image` plugin system:

{% highlight ocaml %}
Library elf_backend
  Path:            lib/bap_image/
  FindlibParent:   bap_image
  FindlibName:     elf_backend
  XMETAExtraLines: plugin_system = "bap.image" # register our plugin
  CompiledObject:  best
  BuildDepends:    bap, core_kernel
  Modules:         Image_elf
{% endhighlight %}

We can also print out the name of all registered BAP plugins:

{% highlight ocaml %}
# List.map ~f:Plugin.name (Plugins.all ());;
- : bytes list = ["bap.image.elf_backend"]
{% endhighlight %}

(As an interesting aside, we do not use first class modules. I asked
our OCaml expert Ivan why. He said first class modules are really only
best needed when you have functions that are similar, e.g., both take
in something of type `t` and return a result of type `int`, but the
type `t`'s are different. In our case the type signature is always
exactly the same.)


## Frontend

The frontend provides an abstraction over executables formats, and is
agnostic to the particular backend.  You shouldn't have to do anything
here, and your users can now use the various `Image` functions and
data structures such as finding entry points (`Image.entry_point`),
architecture (`Image.arch`), and so on.  The complete list of
functions is provided in the `Image` namespace.

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

