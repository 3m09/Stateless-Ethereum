import importlib
import pathlib
import pkgutil


def auto_import_submodules(package, *, ignore_errors=False):
    package_path = pathlib.Path(package.__file__).parent
    module_prefix = package.__name__ + "."
    errors = {}

    for module_info in pkgutil.iter_modules([str(package_path)]):
        module_name = module_prefix + module_info.name
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            if not ignore_errors:
                raise
            errors[module_name] = f"{type(exc).__name__}: {exc}"
    return errors
