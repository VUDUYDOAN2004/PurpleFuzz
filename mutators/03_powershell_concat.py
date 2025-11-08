import random
from mutators.base_mutator import BaseMutator

class PowerShellConcat(BaseMutator):
    """
    Mutate PowerShell commands by randomly concatenating strings.
    Example: 'Get-WmiObject' -> ('Get-Wmi' + 'Object')
    """
    tags = ["powershell"]

    def mutate(self, data):
        parts = data.split(' ')
        if not parts: 
            return data

        # Try to find a word to mutate
        for _ in range(5): # Try 5 times
            idx_to_mutate = random.randint(0, len(parts) - 1)
            word = parts[idx_to_mutate]
            
            # Only mutate long words, not switches (starting with '-')
            # and not already strings (starting with "'")
            if len(word) > 4 and not word.startswith("-") and not word.startswith("'"):
                split_point = random.randint(2, len(word) - 2) # Split in the middle
                part1 = word[:split_point]
                part2 = word[split_point:]
                
                # PowerShell string concatenation syntax
                parts[idx_to_mutate] = f"('{part1}' + '{part2}')"
                return " ".join(parts) # Return immediately when mutation succeeds
        
        return data # Return original if no suitable word found