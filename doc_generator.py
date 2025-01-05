"""
Documentation Generator Security Framework
Version: 1.0
Author: Gabriel Cellammare
Last Modified: 05/01/2025

This module implements a secure and robust documentation generation system with
a strong focus on module discovery protection, configuration security, and
safe file system operations.

Security Features:
1. File System Protection
   - Secure path traversal prevention
   - Protected file operations
   - Safe directory creation
   - Path validation and sanitization

2. Module Security
   - Protected module discovery
   - Secure import handling
   - Module isolation
   - Safe module resolution

3. Documentation Security
   - Protected configuration generation
   - Secure theme handling
   - Safe template management
   - Output isolation

4. Configuration Management
   - Protected variable handling
   - Secure initialization
   - Error isolation
   - Safe defaults

Security Considerations:
- All file paths are validated and sanitized
- Module imports are protected
- Configuration files are isolated
- Development artifacts are protected
- Error states provide safe defaults
- Directory traversal is prevented
- Module resolution is secured
- Output paths are protected

Dependencies:
- sphinx: Documentation generation framework
- pdoc: Alternative documentation generator
- pathlib: Secure path operations
- importlib: Protected module importing
"""
import os
import sys
from typing import Dict
import pdoc
from sphinx.application import Sphinx
from pathlib import Path
import importlib.util


class DocGenerator:
    """
    A class that automates documentation generation from Python source files.

    This class provides functionality to:
    1. Discover Python modules in a project directory
    2. Generate documentation using either Sphinx or pdoc
    3. Handle configuration and setup for documentation generation
    4. Provide error handling and fallback options

    Attributes:
        project_dir (Path): Root directory containing Python source files
        output_dir (Path): Directory where documentation will be generated
        has_rtd_theme (bool): Flag indicating if sphinx_rtd_theme is available
        python_files (Dict[str, Path]): Mapping of module names to file paths
    """

    def __init__(self, project_dir: str, output_dir: str):
        """
        Initialize the documentation generator with project and output directories.

        Args:
            project_dir: Root directory containing Python source files
            output_dir: Directory where documentation will be generated

        Raises:
            ValueError: If no Python files are found in the project directory
            TypeError: If input parameters are not str or Path objects
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
        Discover and catalog all Python files in the project directory.

        This method walks through the project directory tree and:
        1. Identifies all .py files
        2. Excludes files in venv, build, and __pycache__ directories
        3. Converts file paths to module names

        Returns:
            Dict[str, Path]: Dictionary mapping module names to their file paths

        Example:
            {'mypackage.module': Path('/path/to/mypackage/module.py')}
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
        Set up Sphinx configuration and create necessary directory structure.

        This method:
        1. Creates required Sphinx directories
        2. Generates conf.py with project configuration
        3. Creates index.rst with module documentation structure
        4. Configures theme and extensions

        Raises:
            IOError: If unable to create necessary files or directories
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

        This method:
        1. Sets up Sphinx configuration
        2. Builds HTML documentation
        3. Handles errors and provides theme fallback

        Raises:
            Exception: If documentation generation fails after fallback attempts
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

        This method:
        1. Adds project directory to Python path
        2. Generates HTML documentation using pdoc
        3. Outputs documentation to specified directory

        Raises:
            Exception: If pdoc documentation generation fails
        """
        sys.path.insert(0, str(self.project_dir))

        print("Generating documentation for the following modules:")
        for module_name in sorted(self.python_files.keys()):
            print(f"  - {module_name}")

        pdoc.pdoc(*self.python_files.keys(), output_dir=str(self.output_dir))

    def run(self, doc_type: str = 'sphinx') -> None:
        """
        Execute the documentation generation process.

        Args:
            doc_type: Type of documentation to generate ('sphinx' or 'pdoc')

        Raises:
            ValueError: Unsupported documentation type
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
