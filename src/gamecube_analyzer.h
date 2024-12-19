#ifndef GAMECUBE_ANALYZER_H
#define GAMECUBE_ANALYZER_H

#include <string>
#include <vector>
#include "renderware.h" // Include Renderware definitions

class GameCubeAnalyzer {
public:
    GameCubeAnalyzer(const std::string& gamePath);
    bool loadGameFiles();
    std::vector<Renderware::Model> extractModels();
    std::vector<Renderware::Texture> extractTextures();

private:
    std::string gamePath;
};

#endif // GAMECUBE_ANALYZER_H
