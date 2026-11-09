from django import template

register = template.Library()


@register.filter
def get_item(dictionary, key):
    """Usage: {{ mydict|get_item:key }} — dict.get(key) isn't available directly
    in Django templates because the key comes from a loop variable, not a literal."""
    if not dictionary:
        return None
    return dictionary.get(key)


@register.filter
def get_delivery_attachment(entry, key):
    """Usage: {{ entry|get_delivery_attachment:key }} — returns the FieldFile for
    that delivery source's attachment (talabat/tmdone/khedmah/callcenter), or None."""
    field = getattr(entry, f'delivery_attachment_{key}', None)
    return field if field else None


@register.simple_tag
def returned_deposits_count():
    """How many bank deposits Audit sent back and the collector has not corrected yet."""
    from salesapp.models import BankDeposit
    return BankDeposit.objects.filter(returned=True).count()
