#include <stack>
#include <string>
#include "infixtopostfix.h"

using namespace std;

string infix_to_postfix ( string infix ) {
	string postfix="";
	stack <char> S;
	for ( int i = 0; i < infix.length(); i++ ) {
		if ( infix[i] == ' ' ) {
			continue;
		} else if ( infix[i] >= '0' && infix[i] <= '9' ) {
			postfix += infix[i];
			while ( infix[i+1] >= '0' && infix[i+1] <= '9' ) {
				i++;
				postfix += infix[i];
			}
			postfix += " ";
		} else if ( infix[i] == '+' || infix[i] == '-' ||
					infix[i] == '*' || infix[i] == '/' ||
					infix[i] == '%' || infix[i] == '&' ||
					infix[i] == '|' || infix[i] == '^'   ) {
			while(!S.empty() && S.top() != '(' && has_higher_precedence(S.top(),infix[i])) {
				postfix += S.top();
				postfix += " ";
				S.pop();
			}
			S.push(infix[i]);
		}
		else if (infix[i] == '(') {
			S.push(infix[i]);
		}
		else if(infix[i] == ')') {
			while(!S.empty() && S.top() != '(') {
				postfix += S.top();
				postfix += " ";
				S.pop();
			}
			S.pop();
		}
	}
	while(!S.empty()) {
		postfix += S.top();
		postfix+= " ";
		S.pop();
	}
	return postfix;
}

int operator_weight ( char op ) {
	int weight = -1;
	switch(op) {
		case '|':
			weight = 1;
			break;
		case '^':
			weight = 2;
			break;
		case '&':
			weight = 3;
			break;
		case '+':
		case '-':
			weight = 4;
			break;
		case '*':
		case '/':
		case '%':
			weight = 5;
			break;
	}
	return weight;
}

int has_higher_precedence ( char op1, char op2 ) {
	int op1Weight = operator_weight(op1);
	int op2Weight = operator_weight(op2);
	return op1Weight >= op2Weight ? true: false;
}
