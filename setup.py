from setuptools import find_packages, setup

REQUIREMENTS = open("requirements.txt").read().splitlines()

setup(name='berglas_python',
      version='0.3.4',
      url='https://github.com/guillaumeblaquiere/berglas-python',
      license='Apache 2.0',
      author='Guillaume Blaquiere',
      author_email='guillaume.blaquiere@gmail.com',
      description='Decipher the Berglas keys',
      packages=find_packages(exclude=['tests','examples']),
      long_description=open("README.md", "r").read(),
      long_description_content_type="text/markdown",
      install_requires=REQUIREMENTS,
      py_modules=["berglas_python"],
      zip_safe=False,
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: Apache Software License",
          "Operating System :: OS Independent", ],
      )
