import os

from jinja2 import Template, Environment, PackageLoader

def renderer(data, template_file, verbose=False):
    """
    Render the template with supplied context.
    Example template_file: "blacklist/lookup"

    """
    env = Environment(loader=PackageLoader('riskiq', 'templates'))
    template = env.get_template(template_file)
    return template.render(data=data, verbose=verbose).encode('utf-8').rstrip()
