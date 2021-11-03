from setuptools import setup


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='restalker',
      version='1.1.0.1',
      description="Text analyzer package",
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://gitlab.com/junquera/stalker',
      author='Javier Junquera Sánchez',
      author_email='javier@junquera.io',
      license='MIT',
      packages=['restalker'],
      install_requires=[
        'bs4',
        'nltk',
        'numpy',
        'nltk',
        'rake-nltk'
      ],
      entry_points=dict(
        console_scripts= [
            'restalker=restalker.restalker:main'
        ]
      )
)

