
import os
import sys
sys.path.insert(0, os.path.abspath('..'))

import sphinx_rtd_theme


project = 'CryptoFolio'
copyright = '2024'
author = 'Gabriel Cellammare'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.githubpages',
]

autodoc_member_order = 'bysource'
add_module_names = False
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Migliora la formattazione del codice
pygments_style = 'sphinx'
