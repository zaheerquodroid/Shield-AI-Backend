"""
Test file for CSEC-36: Unsafe AI-generated code execution
This file contains patterns that should trigger code analysis warnings.
"""


# Test Case 1: Direct exec() without validation (DANGEROUS)
def execute_ai_script_unsafe(script_code):
    """Executes AI-generated code without validation - VULNERABLE!"""
    exec(script_code)  # Should be detected


# Test Case 2: eval() without validation (DANGEROUS)
def run_calculation(expression):
    """Evaluates user/AI expression without validation - VULNERABLE!"""
    result = eval(expression)  # Should be detected
    return result


# Test Case 3: compile() without validation
def compile_and_run(source_code):
    """Compiles and executes code without validation"""
    compiled = compile(source_code, '<string>', 'exec')  # Should be detected
    exec(compiled)


# Test Case 4: subprocess without validation
def run_command(cmd):
    """Runs system command from AI - DANGEROUS!"""
    import subprocess
    subprocess.run(cmd, shell=True)  # Should be detected


# Test Case 5: Dynamic import without validation
def load_module(module_name):
    """Dynamically imports module - can be exploited"""
    module = __import__(module_name)  # Should be detected
    return module


# Test Case 6: AI script executor without safety checks
class AIScriptExecutor:
    """Executes AI-generated scripts - UNSAFE"""

    def execute(self, llm_generated_code):
        """Execute code from LLM without validation"""
        # VULNERABLE: No code analysis before execution
        exec(llm_generated_code)  # Should be detected

    def run_test(self, test_code):
        """Run test code without validation"""
        eval(test_code)  # Should be detected


# Test Case 7: Combining AI generation with execution
def ai_code_runner(prompt):
    """Gets code from AI and executes it - DANGEROUS pattern"""
    # Simulated AI call
    ai_response = get_ai_code(prompt)

    # VULNERABLE: Direct execution without analysis
    exec(ai_response['code'])  # Should be detected


def get_ai_code(prompt):
    """Simulated AI code generation"""
    return {'code': 'print("Hello from AI")'}


# Test Case 8: LLM with exec pattern
def llm_execute_pattern():
    """Pattern: llm.generate...exec() - should be detected"""
    code = llm.generate_code("write factorial function")
    exec(code)  # Should be detected


# Simulated LLM object
class llm:
    @staticmethod
    def generate_code(prompt):
        return "def factorial(n): return 1 if n <= 1 else n * factorial(n-1)"
