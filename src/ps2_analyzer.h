#ifndef PS2_ANALYZER_H
#define PS2_ANALYZER_H

#include <string>
#include <vector>
#include "renderware.h" // Include Renderware definitions

class PS2Analyzer {
public:
    PS2Analyzer(const std::string& gamePath);
    bool loadGameFiles();
    std::vector<Renderware::Model> extractModels();
    std::vector<Renderware::Texture> extractTextures();

private:
    std::string gamePath;
};

#endif // PS2_ANALYZER_H
