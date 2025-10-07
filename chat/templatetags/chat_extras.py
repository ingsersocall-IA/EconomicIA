from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe
import re

register = template.Library()

CODE_BLOCK_RE = re.compile(r"```([a-zA-Z0-9_+-]*)\n([\s\S]*?)```", re.MULTILINE)


@register.filter(name="render_codeblocks")
def render_codeblocks(value: str) -> str:
    """Renderiza bloques de código estilo Markdown (```lang\n...```).

    - Escapa todo el contenido por defecto
    - Reemplaza los bloques por <pre><code class="language-...">...</code></pre>
    - Conserve saltos de línea en texto normal como <br>
    """
    if not isinstance(value, str):
        value = str(value)

    output_parts = []
    last_end = 0
    for m in CODE_BLOCK_RE.finditer(value):
        # Texto previo al bloque de código
        before = value[last_end:m.start()]
        if before:
            escaped = escape(before).replace("\n", "<br/>")
            output_parts.append(escaped)

        lang = m.group(1) or ""
        code = m.group(2)
        code_escaped = escape(code)
        lang_class = f" language-{lang}" if lang else ""
        pre = (
            f'<pre class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-100 '
            f'rounded p-3 overflow-x-auto text-sm"><code class="{lang_class}">{code_escaped}'
            f"</code></pre>"
        )
        output_parts.append(pre)
        last_end = m.end()

    # Resto del texto tras el último bloque
    tail = value[last_end:]
    if tail:
        output_parts.append(escape(tail).replace("\n", "<br/>"))

    return mark_safe("".join(output_parts))


# Helper para agregar clases en inputs de forms desde template
@register.filter(name='add_class')
def add_class(field, css):
    try:
        return field.as_widget(attrs={'class': css})
    except Exception:
        return field


