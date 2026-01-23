from restalker import restalker
from testing import tools

current_dir = './testing/'
text, expected = tools.get_data(current_dir, 'locations')

stalker = restalker.reStalker(all=True)
results = stalker.parse(text)

results = tools.restalker_to_array(results)
print(tools.compare_lists(results, expected))