from abc import ABC, abstractmethod

class BaseMutator(ABC):
    """
    Template class for all mutators
    
    
    'tags' is a list of command types that this mutator can be applied to
    Valid tags: 'cmd', 'powershell', 'generic', and name seeds according to tag with structure "{tag}_..........txt"
    """
    tags = ["generic"] # Default is 'generic' (mutator applies to all command types)
    
    @abstractmethod
    def mutate(self, data):
        """
        This function takes a command-line string (data) and
        returns a mutated command-line string
        """
        pass