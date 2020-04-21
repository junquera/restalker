from setuptools import setup

setup(name='stalker',
      version='0.4.2',
      description='',
      url='https://gitlab.com/junquera/stalker',
      author='Javier Junquera Sánchez',
      author_email='javier@junquera.xyz',
      license='MIT',
      packages=['stalker'],
      install_requires=[
        'bs4',
        'nltk'
      ],
      zip_safe=False)
