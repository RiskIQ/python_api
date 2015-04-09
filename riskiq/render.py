import os

from jinja2 import Template, Environment, PackageLoader

def renderer(data, template_file, verbose=False, oneline=False):
    """
    Render the template with supplied context.
    Example template_file: "blacklist/lookup"

    """
    if oneline:
        template_file += '_oneline'
    env = Environment(loader=PackageLoader('riskiq', 'templates'))
    template = env.get_template(template_file)
    return template.render(data=data, verbose=verbose).encode('utf-8').rstrip()
