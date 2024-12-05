#!/bin/zsh

# run as login shell
# change ruby version
# start local server with autreload/show future posts
zsh -l -c 'rvm use 3.3.1; bundle exec jekyll serve --watch --livereload --future'
