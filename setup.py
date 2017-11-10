from setuptools import setup

setup(name='phishing_catcher',
      version='0.1',
      description='Catching malicious phishing domain names using certstream SSL certificates live stream.',
      url='http://github.com/x0rz/phishing_catcher',
      license='GNU GENERAL PUBLIC LICENSE',
      py_modules=['catch_phishing'],
      install_requires=[
          'entropy >= 0.10',
          'certstream >= 1.7',
          'tqdm >= 4.19.4',
      ])
