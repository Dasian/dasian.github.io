# Dasian's Blog
Why are you here? You should check out the running
blog on
[dasian.github.io](https://dasian.github.io)!

## How is it running?
- Github Pages
- Jekyll

[Github Pages](https://pages.github.com/)
allows me to host a static website for free on github. 

[Jekyll](https://jekyllrb.com/)
is a static site generator. I'm also using the
[chirpy theme](https://github.com/cotes2020/jekyll-theme-chirpy)

## Setup
This section is just for taking notes setting this blog
up on my systems

### Ruby Version
The 
[github pages gem](https://pages.github.com/versions/)
depends on a version of jekyll
that isn't compatible with the chirpy theme. To solve
this you can change the local ruby version you're using
with
[RVM](https://wiki.archlinux.org/title/RVM).

RVM needs to be run in a login shell (for some reason)
```bash
zsh -l
```

To check you can run
```bash
type rvm | head -n1
```
The output of the second command should be
`rvm is a shell function from ...`

Now we can use the proper version of ruby
```bash
rvm use 3.3.1
```

### Local Server
This will only work if the ruby version is correct
```bash
bundle exec jekyll serve --watch --livereload
```
then visit
[localhost:4444](http://localhost:4444)
