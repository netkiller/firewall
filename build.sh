python3 setup.py sdist
python3 setup.py install

python3 setup.py sdist bdist_wheel
twine upload dist/*   