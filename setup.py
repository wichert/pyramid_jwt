import os
import sys
from setuptools import setup
from setuptools.command.test import test as test_command

version = '1.4.1'

install_requires = [
    'pyramid',
    'PyJWT',
]

tests_require = [
    'pytest',
    'WebTest',
    'flake8',
]


class PyTest(test_command):
    test_args = ['tests']
    test_suite = True

    def finalize_options(self):
        test_command.finalize_options(self)

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


def get_readme():
    readme = open('README.rst').read()
    example = open(os.path.join('docs', 'example.rst')).read()
    changes = open('changes.rst').read()
    return "%s\n%s\n%s" % (readme, example, changes)


setup(name='pyramid_jwt',
      version=version,
      description='JWT authentication policy for Pyramid',
      long_description=get_readme(),
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
          'Programming Language :: Python :: 3.6',
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
