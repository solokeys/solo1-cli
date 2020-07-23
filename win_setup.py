from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = dict(packages = [], excludes = [])

msiOptions = dict(
    add_to_path = True,
    all_users = True
)

base = 'Console'

executables = [
    Executable('nitropy.py', base=base)
]

setup(name='pynitrokey',
      version = '0.3.2',
      description = 'Nitrokey Python Tools',
      options = dict(build_exe = buildOptions,
                     bdist_msi = msiOptions),
      executables = executables)
