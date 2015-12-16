from setuptools import setup
from setuptools.command.test import test as TestCommand
import sys

version = '1.0'

install_requires = [
    'pyramid',
    'PyJWT',
]

tests_require = [
    'pytest',
    'WebTest',
]


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = ['tests']
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


setup(name='pyramid_jwt',
      version=version,
      description='JWT authentication policy for Pyramid',
      long_description=open('README.rst').read() + '\n' +
              open('changes.rst').read(),
      classifiers=[
          'Intended Audience :: Developers',
          'License :: DFSG approved',
          'License :: OSI Approved :: BSD License',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],
      keywords='Pyramid JWT authentication security',
      author='Wichert Akkerman',
      author_email='wichert@wiggy.net',
      url='https://github.com/wichert/pyramid_jwt',
      license='BSD',
      packages=['pyramid_jwt'],
      package_dir={'': 'src'},
      include_package_data=True,
      zip_safe=True,
      install_requires=install_requires,
      tests_require=tests_require,
      extras_require={'tests': tests_require},
      cmdclass={'test': PyTest},
      )
