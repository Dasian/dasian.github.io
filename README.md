# Dasian's Blog
Why are you here? You should check out the running
blog on
[dasian.github.io](https://dasian.github.io){:target="_blank"}{:rel="noopener noreferrer"}!

## How is it running?
I'm using
[github pages](https://pages.github.com/){:target="_blank"}{:rel="noopener noreferrer"}.
which allows me to host a static
website for free on github. 
[Jekyll](https://jekyllrb.com/){:target="_blank"}{:rel="noopener noreferrer"}
is used as a static
site generator along with the
[chirpy theme](https://github.com/cotes2020/jekyll-theme-chirpy){:target="_blank"}{:rel="noopener noreferrer"}

## Setup
This section is just for taking notes setting this blog
up on my systems
### Arch
#### Installation
The github pages gem depends on a version of jekyll
that isn't compatible with the chirpy theme. To solve
this you can change the local ruby version you're using
with
[RVM](https://wiki.archlinux.org/title/RVM){:target="_blank"}{:rel="noopener noreferrer"}.

RVM needs to be run in a login shell.
```bash
zsh -l
type rvm | head -n1
```
The output of the second command should be
`rvm is a shell function from ...`

Now we can use the proper version of ruby
```bash
rvm use 3.3.1
```

#### Local Server
This will only work if the ruby version is correct
```bash
bundle exec jekyll serve --watch --livereload
```
then visit
[localhost:4444](http://localhost:4444){:target="_blank"}{:rel="noopener noreferrer"}
