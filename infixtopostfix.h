#ifndef _INFIXTOPOSTFIX_H_
#define _INFIXTOPOSTFIX_H_

#include <string>

std::string infix_to_postfix(std::string);
int operator_weight(char);
int has_higher_precedence(char, char);

#endif
