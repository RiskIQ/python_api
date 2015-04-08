import os

from jinja2 import Template

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')

def renderer(data, datatype, verbose=False):
    """
    Render data of type datatype
    Example datatype: "blacklist/lookup"
    """
    template_path = os.path.join(TEMPLATE_DIR, datatype)
    with open(template_path) as temp_f:
        template_text = temp_f.read()
    template = Template(template_text)
    return template.render(data=data, verbose=verbose).encode('utf-8')
