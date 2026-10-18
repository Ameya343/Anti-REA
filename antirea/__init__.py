"""Anti-REA: threat-informed anti-reverse-engineering hardening toolkit.

Anti-REA does not promise that software becomes impossible to reverse engineer.
Anything that executes on a device an attacker controls can eventually be
analyzed. The goal is defense-in-depth: deny or degrade the specific signals an
analyst (or an AI-assisted platform such as REA) relies on, so that the cost,
time, and skill required to reconstruct your features go up sharply, and so that
genuinely sensitive logic stays off the client entirely.
"""

__version__ = "0.1.0"
