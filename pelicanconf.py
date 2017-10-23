#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = u'Ioannis Kakavas'
SITENAME = u'Economy of mechanism'
SITESUBTITLE = u'Security is hard'
SITEURL = 'http://www.economyofmechanism.com'
ROBOTS = 'index, follow'

COPYRIGHT_YEAR = 2017
CC_LICENSE = { 'name': 'Creative Commons Attribution-NonCommercial-ShareAlike', 'version':'4.0', 'slug': 'by-nc-sa' }

MAIN_MENU = True

PATH = 'content'

TIMEZONE = 'Europe/Athens'

DEFAULT_LANG = u'en'

THEME="/home/ioannis/Documents/blog/Flex"
# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None
DISPLAY_PAGES_ON_MENU = True
# Blogroll
LINKS = (('geocreepy', 'http://www.geocreepy.com'),
        )

# Social widget
SOCIAL = (('twitter', 'https://twitter.com/ilektrojohn'),
        ('github', 'https://github.com/jkakavas'),
        ('linkedin', 'https://linkedin.com/in/jkakavas',),
        ('rss', '//economyofmechanism.com/feeds/all.atom.xml'))


MENUITEMS = (('Archives', '/archives.html'),
             ('Categories', '/categories.html'),
             ('Tags', '/tags.html'),)

DEFAULT_PAGINATION = 10

# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True
