#!/usr/bin/env python3
# i'm not doing this in bash
import re
import sys
import os
import shutil
from datetime import datetime

# TODO better argparse
if len(sys.argv) != 2:
  print(f'usage: {sys.argv[0]} [writeup-name]')

# TODO change based on windows/linux?
vault_path = '/home/dasian/docs/gnosis/6-full-notes/'
img_path = '/home/dasian/docs/gnosis/7-attachments/'

folder = sys.argv[1]
if '.md' in folder:
  folder = folder[:-2]
path = vault_path + folder + '.md'
if not os.path.exists(path):
  print(f'{path} doesn\'t exist')
  exit()

# name our file after conversion date
filename = f'{datetime.today().strftime("%Y-%m-%d")}-{folder}.md'
images = []
dest_file = open(filename, 'w')

# parsing out obsidian links to convert into blog links
# don't start with !
# [] don't include these chars []() + non empty
# () don't include these chars []() + non empty
link_regex = r'(?<!!)\[[^[\]()]+\]\([^[\]()]+\)'

# copy obsidian/note into a blog template and
# replace obsidian formatting with blog formatting
with open(path) as f:
  metadata = True
  for line in f.read().splitlines():

    # migrate obsidian metadata to blog
    if metadata:
      # write header + skip # {folder} h1 tag
      if line == f'# {folder}':
        metadata = False
        header = f'''---
layout: post
title: "{folder.replace('-',' ')} Writeup"
date: {datetime.today().strftime('%Y-%m-%d %H:%M:%S')} -0400
categories: hackthebox HTB-medium
tags: {tags}
---
'''
        dest_file.write(header)
        continue

      # keep obsidian tags
      elif 'Tags' in line:
        tags = line.replace('[[','').replace(']]','').replace('Tags: ','')
        continue
      else:
        continue

    # changing obsidian image to markdown image
    if '![[' in line:
      img_name = line[3:-2]
      no_ext = img_name[:img_name.index('.')]
      images.append(img_name)
      new_format = f'![{no_ext}](images/{folder}/{img_name})'
      dest_file.write(new_format + '\n')

    # open links in new tabs
    elif re.search(link_regex, line):
      def add_newtab(s):
        new_tab = '{:target="_blank"}{:rel="noopener noreferrer"}'
        new_link = s.group(0) + new_tab
        print(f'Changing link to {new_link}\n')
        return new_link
      new_line = re.sub(link_regex, add_newtab, line)
      dest_file.write(new_line + '\n')

    # remove credentials
    elif '## Credential' in line:
      break

    # normal line
    else:
      dest_file.write(line + '\n')

dest_file.close()

# copy image files
blog_img_path = f'../images/{folder}/'
if not os.path.isdir(blog_img_path):
  os.makedirs(blog_img_path)
for img in images:
  src = img_path + img
  dest = blog_img_path + img
  print(f'Copying {src} to {dest}\n')
  shutil.copyfile(src, dest)
