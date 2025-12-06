import random
from mutators.base_mutator import BaseMutator

class ObfuscateCase(BaseMutator):
    tags = ["generic"]
    
    def mutate(self, data):
        mutated_list = []
        for char in data:
            if char.isalpha():
                #case sensitive and non-sensitive
                mutated_list.append(random.choice([char.lower(), char.upper()]))
            else:
                mutated_list.append(char)
        
        return "".join(mutated_list)