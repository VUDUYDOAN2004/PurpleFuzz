import random
from mutators.base_mutator import BaseMutator

class AddEscapeChars(BaseMutator):
    """
    insert random syntax into the command line
    """
    tags = ["cmd"]
    
    def mutate(self, data):
        parts = data.split(' ')
        if not parts:
            return data

        # Insert words that have 1-3 word length
        for _ in range(random.randint(1, 3)):
            idx_to_mutate = random.randint(0, len(parts) - 1)
            word = parts[idx_to_mutate]
            
            # Longer than 1
            if len(word) > 1:
                # Add one or two syntax
                for _ in range(random.randint(1, 2)):
                    split_point = random.randint(1, len(word) - 1)
                    word = word[:split_point] + '^' + word[split_point:]
            
            parts[idx_to_mutate] = word
            
        return " ".join(parts)