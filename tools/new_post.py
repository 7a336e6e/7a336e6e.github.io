import getpass
from datetime import datetime

delim = '---'

title = input('Post title: ')
filename = f'{datetime.now().strftime("%Y-%m-%d")}-{title.replace(" ", "-").lower()}.md'

author = getpass.getuser()

date = f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} +0300'

categories = input('Input categories separate by a comma: ')
categories = categories.split(',')

description = input('Input post description: ')

tags = input('Input tags separate by a comma: ')
tags = tags.split(',')

output = open(f'_posts/{filename}','w')
output.write(delim + '\n')

output.write(f'title: {title}\n')
output.write(f'description: {description}\n')
output.write(f'author: {author}\n')
output.write(f'date: {date}\n')

output_categories = '['
for cat in categories:
    output_categories += f'{cat}, '

output_categories += ']'
output_categories = output_categories.replace(', ]', ']')

output.write(f'categories: {output_categories}\n')

output_tags = '['
for tag in tags:
    output_tags += f'{tag}, '

output_tags += ']'
output_tags = output_tags.replace(', ]', ']')

output.write(f'tags: {output_tags}\n')

output.write(delim + '\n')
