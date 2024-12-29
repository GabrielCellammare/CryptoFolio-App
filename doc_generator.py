import os
import sys
from typing import List, Optional, Dict
import pdoc
import sphinx.ext.autodoc
from sphinx.application import Sphinx
from pathlib import Path
import importlib.util


class DocGenerator:
    """
    A class to automate documentation generation from multiple Python source files.
    Supports both Sphinx and pdoc documentation formats with automatic module discovery.
    """

    def __init__(self, project_dir: str, output_dir: str):
        """
        Initialize the documentation generator.

        Args:
            project_dir: Root directory containing Python source files
            output_dir: Directory where documentation will be generated
        """
        self.project_dir = Path(project_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.has_rtd_theme = importlib.util.find_spec(
            'sphinx_rtd_theme') is not None

        # Trova tutti i file Python nel progetto
        self.python_files = self._discover_python_files()

        if not self.python_files:
            raise ValueError(f"No Python files found in: {project_dir}")

    def _discover_python_files(self) -> Dict[str, Path]:
        """
        Discover all Python files in the project directory.

        Returns:
            Dict[str, Path]: Dictionary mapping module names to file paths
        """
        python_files = {}
        for file_path in self.project_dir.glob('**/*.py'):
            # Ignora i file nelle directory venv e build
            if any(part in str(file_path) for part in ['venv', 'build', '__pycache__']):
                continue

            # Converti il percorso del file in un nome di modulo
            relative_path = file_path.relative_to(self.project_dir)
            module_name = str(relative_path.with_suffix('')
                              ).replace(os.sep, '.')

            python_files[module_name] = file_path

        return python_files

    def setup_sphinx(self) -> None:
        """
        Set up Sphinx configuration and create necessary files.
        Automatically includes all discovered Python modules.
        """
        sphinx_dirs = ['_static', '_templates',
                       '_build/html', '_build/doctrees']
        for dir_name in sphinx_dirs:
            (self.output_dir / dir_name).mkdir(parents=True, exist_ok=True)

        # Determina il tema
        theme_name = 'sphinx_rtd_theme' if self.has_rtd_theme else 'alabaster'
        theme_extension = "\nimport sphinx_rtd_theme\n" if self.has_rtd_theme else ""

        # Crea conf.py con configurazione migliorata
        conf_content = f'''
import os
import sys
sys.path.insert(0, os.path.abspath('..'))
{theme_extension}

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
html_theme = '{theme_name}'
html_static_path = ['_static']

# Migliora la formattazione del codice
pygments_style = 'sphinx'
'''
        with open(self.output_dir / 'conf.py', 'w', encoding='utf-8') as f:
            f.write(conf_content)

        # Crea index.rst con riferimenti a tutti i moduli
        modules_content = []
        for module_name in sorted(self.python_files.keys()):
            modules_content.append(f'''
{module_name}
{'=' * len(module_name)}

.. automodule:: {module_name}
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __init__
''')

        index_content = f'''
Welcome to Project Documentation of CryptoFolio
==============================

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: Modules:

   modules

Detailed Module Documentation
---------------------------

{os.linesep.join(modules_content)}

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
'''
        with open(self.output_dir / 'index.rst', 'w', encoding='utf-8') as f:
            f.write(index_content)

    def generate_sphinx_docs(self) -> None:
        """
        Generate Sphinx documentation for all discovered Python files.
        Includes improved error handling and fallback options.
        """
        try:
            self.setup_sphinx()

            # Aggiungi la directory del progetto al path di Python
            sys.path.insert(0, str(self.project_dir))

            app = Sphinx(
                srcdir=str(self.output_dir),
                confdir=str(self.output_dir),
                outdir=str(self.output_dir / '_build/html'),
                doctreedir=str(self.output_dir / '_build/doctrees'),
                buildername='html',
                freshenv=True
            )

            print("Generating documentation for the following modules:")
            for module_name in sorted(self.python_files.keys()):
                print(f"  - {module_name}")

            app.build()

        except Exception as e:
            print(f"Warning during Sphinx build: {e}")
            if self.has_rtd_theme:
                print("Retrying with default theme...")
                self.has_rtd_theme = False
                self.generate_sphinx_docs()
            else:
                raise

    def generate_pdoc_docs(self) -> None:
        """
        Generate pdoc documentation for all discovered Python files.
        Creates a simpler but comprehensive documentation.
        """
        sys.path.insert(0, str(self.project_dir))

        print("Generating documentation for the following modules:")
        for module_name in sorted(self.python_files.keys()):
            print(f"  - {module_name}")

        pdoc.pdoc(*self.python_files.keys(), output_dir=str(self.output_dir))

    def run(self, doc_type: str = 'sphinx') -> None:
        """
        Run the documentation generation process.

        Args:
            doc_type: Type of documentation to generate ('sphinx' or 'pdoc')
        """
        print(f"\nStarting documentation generation...")
        print(f"Source directory: {self.project_dir}")
        print(f"Output directory: {self.output_dir}")
        print(f"Documentation type: {doc_type}")

        if doc_type == 'sphinx':
            self.generate_sphinx_docs()
            print(f"\nDocumentation generated successfully at: {
                  self.output_dir}/_build/html/index.html")
        elif doc_type == 'pdoc':
            self.generate_pdoc_docs()
            print(f"\nDocumentation generated successfully at: {
                  self.output_dir}/index.html")
        else:
            raise ValueError(f"Unsupported documentation type: {doc_type}")


def main():
    """Command-line interface for the documentation generator."""
    if len(sys.argv) < 3:
        print(
            "Usage: python doc_generator.py <project_dir> <output_dir> [doc_type]")
        print("doc_type can be 'sphinx' (default) or 'pdoc'")
        sys.exit(1)

    project_dir = sys.argv[1]
    output_dir = sys.argv[2]
    doc_type = sys.argv[3] if len(sys.argv) > 3 else 'sphinx'

    try:
        generator = DocGenerator(project_dir, output_dir)
        generator.run(doc_type)
    except Exception as e:
        print(f"Error generating documentation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    # python doc_generator.py . ./docs
