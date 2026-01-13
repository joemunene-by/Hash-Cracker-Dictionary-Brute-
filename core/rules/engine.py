"""
Rule Engine

Processes and applies password rules for generating variations
in dictionary attacks.
"""

from typing import Iterator, List, Dict, Any, Optional
from .mutations import MutationRules


class RuleEngine:
    """Engine for processing password rules and generating mutations."""
    
    def __init__(self):
        self.mutations = MutationRules()
        self.custom_rules: List[Dict[str, Any]] = []
        self.rule_stats = {
            'rules_applied': 0,
            'mutations_generated': 0,
            'rules_failed': 0
        }
    
    def add_custom_rule(self, rule_name: str, rule_func: callable, 
                       description: str = ""):
        """
        Add a custom mutation rule.
        
        Args:
            rule_name: Name of the rule
            rule_func: Function that takes a word and returns mutations
            description: Rule description
        """
        self.custom_rules.append({
            'name': rule_name,
            'function': rule_func,
            'description': description,
            'applied_count': 0
        })
    
    def apply_rules(self, word: str, rule_types: List[str] = None,
                   max_mutations: int = 50) -> Iterator[str]:
        """
        Apply specified rules to generate password mutations.
        
        Args:
            word: Original word to mutate
            rule_types: Types of rules to apply (None for all)
            max_mutations: Maximum mutations to generate
            
        Yields:
            Mutated password candidates
        """
        mutations_generated = 0
        
        # Apply built-in mutation rules
        if rule_types is None or 'mutations' in rule_types:
            for mutation in self.mutations.apply_mutations(word, max_mutations):
                yield mutation
                mutations_generated += 1
                self.rule_stats['mutations_generated'] += 1
        
        # Apply custom rules
        if rule_types is None or 'custom' in rule_types:
            for rule in self.custom_rules:
                try:
                    for mutation in rule['function'](word):
                        if mutations_generated >= max_mutations:
                            return
                        
                        yield mutation
                        mutations_generated += 1
                        rule['applied_count'] += 1
                        self.rule_stats['mutations_generated'] += 1
                    
                    self.rule_stats['rules_applied'] += 1
                    
                except Exception as e:
                    self.rule_stats['rules_failed'] += 1
                    continue
        
        self.rule_stats['rules_applied'] += 1
    
    def apply_single_rule(self, word: str, rule_name: str) -> Iterator[str]:
        """
        Apply a single specific rule.
        
        Args:
            word: Word to mutate
            rule_name: Name of rule to apply
            
        Yields:
            Mutated password candidates
        """
        # Check custom rules first
        for rule in self.custom_rules:
            if rule['name'] == rule_name:
                try:
                    for mutation in rule['function'](word):
                        yield mutation
                    self.rule_stats['rules_applied'] += 1
                except Exception:
                    self.rule_stats['rules_failed'] += 1
                return
        
        # Built-in rule types
        if rule_name == 'case_variations':
            for case_func in self.mutations.case_patterns:
                yield case_func(word)
        
        elif rule_name == 'leetspeak':
            yield from self.mutations._apply_leetspeak(word, 100)
        
        elif rule_name == 'prefix_suffix':
            yield from self.mutations._apply_prefix_suffix(word, 100)
        
        else:
            raise ValueError(f"Unknown rule: {rule_name}")
    
    def get_available_rules(self) -> Dict[str, str]:
        """
        Get list of available rules.
        
        Returns:
            Dictionary of rule names and descriptions
        """
        rules = {
            'mutations': 'Built-in mutation rules (case, leetspeak, prefix/suffix)',
            'case_variations': 'Case variation mutations',
            'leetspeak': 'Leetspeak substitutions',
            'prefix_suffix': 'Prefix and suffix combinations'
        }
        
        # Add custom rules
        for rule in self.custom_rules:
            rules[rule['name']] = rule['description']
        
        return rules
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """
        Get rule engine statistics.
        
        Returns:
            Dictionary containing rule statistics
        """
        stats = self.rule_stats.copy()
        
        # Add custom rule stats
        stats['custom_rules'] = []
        for rule in self.custom_rules:
            stats['custom_rules'].append({
                'name': rule['name'],
                'description': rule['description'],
                'applied_count': rule['applied_count']
            })
        
        return stats
    
    def reset_stats(self):
        """Reset rule engine statistics."""
        self.rule_stats = {
            'rules_applied': 0,
            'mutations_generated': 0,
            'rules_failed': 0
        }
        
        for rule in self.custom_rules:
            rule['applied_count'] = 0
    
    def create_common_password_rules(self) -> List[Dict[str, Any]]:
        """
        Create common password mutation rules.
        
        Returns:
            List of common rule definitions
        """
        common_rules = []
        
        # Year suffix rule
        def year_suffix_rule(word: str) -> Iterator[str]:
            years = ['2023', '2024', '2025', '2022', '2021']
            for year in years:
                yield word + year
                yield year + word
        
        common_rules.append({
            'name': 'year_suffix',
            'function': year_suffix_rule,
            'description': 'Add common years as prefix/suffix'
        })
        
        # Keyboard pattern rule
        def keyboard_pattern_rule(word: str) -> Iterator[str]:
            patterns = ['qwerty', 'asdf', '123456', 'qwertyuiop']
            for pattern in patterns:
                yield word + pattern
                yield pattern + word
        
        common_rules.append({
            'name': 'keyboard_patterns',
            'function': keyboard_pattern_rule,
            'description': 'Add common keyboard patterns'
        })
        
        # Common substitutions rule
        def common_substitutions_rule(word: str) -> Iterator[str]:
            subs = {
                'a': ['@', '4'],
                's': ['$', '5'],
                'i': ['!', '1'],
                'o': ['0'],
                'e': ['3']
            }
            
            for char, replacements in subs.items():
                for replacement in replacements:
                    if char in word.lower():
                        yield word.replace(char, replacement)
                        yield word.replace(char.upper(), replacement)
        
        common_rules.append({
            'name': 'common_substitutions',
            'function': common_substitutions_rule,
            'description': 'Common character substitutions'
        })
        
        return common_rules
    
    def load_common_rules(self):
        """Load common password rules into the engine."""
        common_rules = self.create_common_password_rules()
        
        for rule in common_rules:
            self.add_custom_rule(
                rule['name'],
                rule['function'],
                rule['description']
            )
